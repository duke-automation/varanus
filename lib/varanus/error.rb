# frozen_string_literal: true

# Error returned from the Sectigo API
class Varanus::Error < StandardError
  # @return [Integer] Code associated with error
  attr_reader :code

  def initialize code, msg
    @code = code
    super(msg)
  end
end

# Certificate is still being signed.
class Varanus::Error::StillProcessing < Varanus::Error; end
