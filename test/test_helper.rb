$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'simplecov'
SimpleCov.start do
  add_filter '/test/'
  add_filter '/\.bundle/'
end

require 'varanus'

require 'minitest/autorun'
require 'minitest/rg'
require 'webmock/minitest'
require 'mocha/minitest'

class Minitest::Test
  def setup
    WebMock.disable_net_connect!
  end
end
