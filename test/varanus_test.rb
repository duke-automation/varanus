require "test_helper"

class VaranusTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Varanus::VERSION
  end
end
