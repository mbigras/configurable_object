# Configurable Object

> Build a configurable Ruby object with defaults by studying vault-ruby

## Usage example

```
ruby -I . <<EOF
require 'configurable_object'

o = C.new
o = C.new(foo: "flap")
o.configure do |o|
  o.bar = "jacks"
end
p o.options
EOF
{:foo=>"flap", :bar=>"jacks", :baz=>"default baz"}
```

## Links

* https://github.com/hashicorp/vault-ruby

