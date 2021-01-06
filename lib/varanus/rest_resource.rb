# frozen_string_literal: true

# An abstract class for rest resources
# Rest resources should not be initialized directly.  They should be created by methods
# on Varanus
class Varanus::RestResource
  # :nodoc:
  def initialize varanus
    @varanus = varanus
  end

  private

  def check_result result
    body = result.body
    return unless body.is_a?(Hash)
    return if body['code'].nil?

    klass = Varanus::Error
    if body['code'] == 0 && body['description'] =~ /process/
      klass = Varanus::Error::StillProcessing
    end

    raise klass.new(body['code'], body['description'])
  end

  def get path
    result = @varanus.connection.get(path)
    check_result result
    result.body
  end

  def post path, *args
    result = @varanus.connection.post(path, *args)
    check_result result
    result.body
  end
end
