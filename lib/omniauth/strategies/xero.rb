require "omniauth/strategies/oauth"

module OmniAuth
  module Strategies
    class Xero < OmniAuth::Strategies::OAuth

      args [:consumer_key, :consumer_secret]

      option :client_options, {
        access_token_path:  "/oauth/AccessToken",
        authorize_path:     "/oauth/Authorize",
        request_token_path: "/oauth/RequestToken",
        signature_method:   "RSA-SHA1",
        ssl_client_cert:    OpenSSL::X509::Certificate.new(File.read("xero-publickey.cer")),
        ssl_client_key:     OpenSSL::PKey::RSA.new(File.read("xero-public_privatekey.pfx")),
        private_key_file:   "#{Rails.root}/xero-privatekey.pem",
        site:               "https://api-partner.network.xero.com",
        authorize_url:      "https://api.xero.com/oauth/Authorize",
        xero_url:           "https://api-partner.network.xero.com/api.xro/2.0"
      }

      def consumer
        consumer = ::OAuth::Consumer.new(options.consumer_key, options.consumer_secret, options.client_options)
        consumer.http.open_timeout = options.open_timeout if options.open_timeout
        consumer.http.read_timeout = options.read_timeout if options.read_timeout
        consumer.http.cert = options.client_options[:ssl_client_cert]
        consumer.http.key = options.client_options[:ssl_client_key]
        consumer
      end

      credentials do
        {
          token:                    access_token.token,
          secret:                   access_token.secret,
          expires_at:               (Time.now + Integer(access_token.params[:oauth_expires_in])).to_i,
          session_handle:           access_token.params[:oauth_session_handle],
          authorization_expires_at: access_token.params[:oauth_authorization_expires_in]
        }
      end

      info do
        {
          first_name: raw_info["FirstName"],
          last_name:  raw_info["LastName"],
          email:      raw_info["EmailAddress"]
        }
      end

      uid { raw_info["UserID"] }

      extra do
        {
          raw_info: raw_info,
          xero_org_muid: access_token.params[:xero_org_muid]
        }
      end

      private

      def raw_info
        @raw_info ||= users.find { |user| user["IsSubscriber"] } || users.first
      end

      def users
        @users ||= JSON.parse(access_token.get("/api.xro/2.0/Users", {'Accept'=>'application/json'}).body)["Users"]
      end
    end
  end
end
