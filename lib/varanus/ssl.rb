# An connection to the SSL/TSL API.  This should not be initialized directly.  Instead,
# use Varanus#ssl
class Varanus::SSL
  # :nodoc:
  def initialize varanus
    @varanus = varanus
  end

  # Return Array of certificate types that can be used
  def certificate_types
    @certificate_types ||= get('types')
  end

  private

  def check_result result
    body = result.body
    return unless body.is_a?(Hash)
    return if body['code'].nil?

    raise Varanus::Error.new(body['code'], body['description'])
  end

  def connection
    @connection ||= Faraday.new(url: 'https://cert-manager.com/api/ssl/v1') do |conn|
      conn.request :json
      conn.response :json, content_type: /\bjson$/

      conn.headers['login'] = @varanus.username
      conn.headers['password'] = @varanus.password
      conn.headers['customerUri'] = @varanus.customer_uri

      conn.adapter Faraday.default_adapter
    end
  end

  def get path
    result = connection.get(path)
    check_result result
    result.body
  end
end
