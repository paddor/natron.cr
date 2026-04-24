require "minitest/autorun"
require "../src/natron"

{% for path in `find test/natron -name '*_test.cr' | sort`.stringify.split('\n').reject(&.empty?) %}
  require {{ "../" + path.id.stringify }}
{% end %}
