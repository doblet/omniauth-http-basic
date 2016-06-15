require 'omniauth'
require 'net/http'

module OmniAuth
  module Strategies
    class HttpBasic
      include OmniAuth::Strategy

      args [:endpoint]

      option :title,   "Http Basic"
      option :headers, {}

      # NOT IMPLEMENTED FOR HTTP BASIC
      # There's no need to make a request as the username and password are
      # encoded in the HTTP Authentication header.
      # def request_phase
      # end

      def callback_phase
        return fail!(:invalid_credentials) if !authentication_response
        super
      end

      protected

        def user_name_and_password
          # TODO: hard dependency on Rails. is this okay?
          @user_name_and_password ||= HttpAuthentication::Basic.user_name_and_password
        end

        def username
          user_name_and_password.first
        end

        def password
          user_name_and_password.last
        end

        def authentication_response
          unless @authentication_response
            return unless username && password

            @authentication_response = User.authenticate(username, password)
          end

          @authentication_response
        end

    end
  end
end
