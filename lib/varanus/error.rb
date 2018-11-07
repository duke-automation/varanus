# Error returned from API
class Varanus::Error < StandardError
  # Numeric code associated with error
  attr_reader :code

  def initialize code, msg
    @code = code
    super(msg)
  end
end

class Varanus::Error::StillProcessing < Varanus::Error; end
