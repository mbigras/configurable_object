module Configurable
  def self.keys
    @keys ||= [:foo, :bar, :baz]
  end

  attr_accessor *Configurable.keys

  def configure
    yield self
  end

  def options
    Hash[Configurable.keys.map { |key| [key, public_send(key)] }]
  end
end

module Defaults
  class << self
    def foo
      "default foo"
    end
    def bar
      "default bar"
    end
    def baz
      "default baz"
    end
  end
end

class C
  include Configurable

  def initialize(options = {})
    Configurable.keys.each do |key|
      value = options.key?(key) ? options[key] : Defaults.public_send(key)
      instance_variable_set(:"@#{key}", value)
    end
  end
end

