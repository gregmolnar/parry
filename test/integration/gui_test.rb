# frozen_string_literal: true

require "test_helper"

module Parry
  class GuiTest < ActionDispatch::IntegrationTest
    test "the root of the engine lists the rules" do
      create_rule(kind: "blocklist", value: "203.0.113.4", name: "Scraper")

      get "/parry"

      assert_response :success
      assert_select "h1", "Rules"
      assert_select "td", /203\.0\.113\.4/
      assert_select "td", /Scraper/
    end

    test "the rules list is empty until a rule is added" do
      get "/parry/rules"

      assert_response :success
      assert_select ".parry-empty", /No rules yet/
    end

    test "the new rule form is rendered" do
      get "/parry/rules/new"

      assert_response :success
      assert_select "form[action=?]", "/parry/rules"
      assert_select "select[name=?]", "rule[kind]"
      assert_select "input[name=?]", "rule[value]"
      assert_select "input[name=?]", "rule[limit]"
      assert_select "input[name=?]", "rule[path]"
    end

    test "the new rule form starts on honeypot" do
      get "/parry/rules/new"

      assert_select "select[name=?] option[selected=selected]", "rule[kind]" do |options|
        assert_equal "honeypot", options.first["value"]
      end
    end

    test "the form honours the kind in the query string, falling back to honeypot" do
      get "/parry/rules/new", params: {kind: "throttle"}
      assert_select "select[name=?] option[selected=selected]", "rule[kind]" do |options|
        assert_equal "throttle", options.first["value"]
      end

      get "/parry/rules/new", params: {kind: "nonsense"}
      assert_select "select[name=?] option[selected=selected]", "rule[kind]" do |options|
        assert_equal "honeypot", options.first["value"]
      end
    end

    test "creating a blocklist rule" do
      post "/parry/rules", params: {rule: {kind: "blocklist", value: "203.0.113.4", name: "Scraper"}}

      assert_redirected_to "/parry/rules"
      follow_redirect!
      assert_select ".parry-flash--notice", /Rule created/

      rule = Parry.store.all.sole
      assert_equal "blocklist", rule.kind
      assert_equal "203.0.113.4", rule.value
      assert_equal "Scraper", rule.name
    end

    test "creating a throttle rule" do
      post "/parry/rules", params: {
        rule: {kind: "throttle", name: "logins", limit: "5", period: "60", path: "/login"}
      }

      assert_redirected_to "/parry/rules"

      rule = Parry.store.all.sole
      assert_equal "throttle", rule.kind
      assert_equal 5, rule.limit
      assert_equal 60, rule.period
      assert_equal "/login", rule.path
    end

    test "creating a honeypot rule" do
      post "/parry/rules", params: {rule: {kind: "honeypot", path: "/.env", name: "Env probe"}}

      assert_redirected_to "/parry/rules"

      rule = Parry.store.all.sole
      assert_equal "honeypot", rule.kind
      assert_equal "/.env", rule.path
      assert_equal "Env probe", rule.name
    end

    test "creating a regex honeypot" do
      post "/parry/rules", params: {
        rule: {kind: "honeypot", path_match: "regex", path: "\\.(env|git)", name: "Config probe"}
      }

      assert_redirected_to "/parry/rules"

      rule = Parry.store.all.sole
      assert_equal "regex", rule.path_match
      assert_equal "\\.(env|git)", rule.path

      get_as "203.0.113.4", "/.git/config"
      assert_response :forbidden
    end

    test "an unparseable regex is rejected" do
      post "/parry/rules", params: {rule: {kind: "honeypot", path_match: "regex", path: "wp-(login"}}

      assert_response :unprocessable_entity
      assert_select ".parry-errors", /not a valid regular expression/
      assert_empty Parry.store.all
    end

    test "the rules list marks regex honeypots" do
      create_rule(kind: "honeypot", path_match: "regex", path: "\\.(env|git)")

      get "/parry/rules"

      assert_response :success
      assert_select ".parry-tag--regex", "regex"
      assert_select "td", /Blocklists any host whose path matches/
    end

    test "the form offers a way to match the path" do
      get "/parry/rules/new"

      assert_select "select[name=?]", "rule[path_match]"
      assert_select "select[name=?] option", "rule[path_match]", count: 2
    end

    test "a honeypot without a path is rejected" do
      post "/parry/rules", params: {rule: {kind: "honeypot", name: "Env probe"}}

      assert_response :unprocessable_entity
      assert_select ".parry-errors", /Path can't be blank/
      assert_empty Parry.store.all
    end

    test "a honeypot created through the GUI catches hosts right away" do
      post "/parry/rules", params: {rule: {kind: "honeypot", path: "/.env"}}

      get_as "203.0.113.4", "/.env"
      assert_response :forbidden

      get_as "203.0.113.4", "/"
      assert_response :forbidden
    end

    test "the rules list shows honeypots" do
      create_rule(kind: "honeypot", path: "/.env", name: "Env probe")

      get "/parry/rules"

      assert_response :success
      assert_select ".parry-tag--honeypot", "Honeypot"
      assert_select "td", /\/\.env/
      assert_select "td", /Blocklists any host requesting this path/
    end

    test "an invalid rule is rendered again with its errors" do
      post "/parry/rules", params: {rule: {kind: "blocklist", value: "not-an-ip"}}

      assert_response :unprocessable_entity
      assert_select ".parry-errors", /not a valid IP address/
      assert_empty Parry.store.all
    end

    test "editing a rule" do
      rule = create_rule(kind: "blocklist", value: "203.0.113.4")

      get "/parry/rules/#{rule.id}/edit"
      assert_response :success
      assert_select "input[name=?][value=?]", "rule[value]", "203.0.113.4"

      patch "/parry/rules/#{rule.id}", params: {rule: {kind: "safelist", value: "203.0.113.5"}}

      assert_redirected_to "/parry/rules"
      updated = Parry.store.find(rule.id)
      assert_equal "safelist", updated.kind
      assert_equal "203.0.113.5", updated.value
    end

    test "an invalid update is rejected" do
      rule = create_rule(kind: "blocklist", value: "203.0.113.4")

      patch "/parry/rules/#{rule.id}", params: {rule: {kind: "blocklist", value: ""}}

      assert_response :unprocessable_entity
      assert_equal "203.0.113.4", Parry.store.find(rule.id).value
    end

    test "editing a rule that no longer exists" do
      get "/parry/rules/missing/edit"

      assert_redirected_to "/parry/rules"
      follow_redirect!
      assert_select ".parry-flash--alert", /Rule not found/
    end

    test "deleting a rule" do
      rule = create_rule(kind: "blocklist", value: "203.0.113.4")

      delete "/parry/rules/#{rule.id}"

      assert_redirected_to "/parry/rules"
      assert_empty Parry.store.all
    end

    test "a rule created through the GUI applies right away" do
      post "/parry/rules", params: {rule: {kind: "blocklist", value: "203.0.113.4"}}

      get_as "203.0.113.4"
      assert_response :forbidden
    end

    test "exporting downloads a file of the rules" do
      create_rule(kind: "blocklist", value: "203.0.113.4", name: "Scraper")

      get "/parry/rules/export"

      assert_response :success
      assert_equal "application/json", response.media_type
      assert_match(/attachment; filename="parry-rules-\d{8}-\d{6}\.json"/, response.headers["Content-Disposition"])

      data = JSON.parse(response.body)
      assert_equal 1, data["rules"].size
      assert_equal "Scraper", data["rules"].sole["name"]
    end

    test "the import page is rendered" do
      get "/parry/rules/import"

      assert_response :success
      assert_select "form[action=?][enctype=?]", "/parry/rules/import", "multipart/form-data"
      assert_select "input[type=file][name=?]", "file"
      assert_select "textarea[name=?]", "pasted"
      assert_select "input[type=radio][name=?]", "mode", count: 2
    end

    test "importing pasted rules" do
      post "/parry/rules/import", params: {
        pasted: JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "203.0.113.4"}]})
      }

      assert_redirected_to "/parry/rules"
      follow_redirect!
      assert_select ".parry-flash--notice", /Imported 1 rule\./

      assert_equal "203.0.113.4", Parry.store.all.sole.value

      # And it is in force, not just stored.
      get_as "203.0.113.4"
      assert_response :forbidden
    end

    test "importing an uploaded file" do
      create_rule(kind: "blocklist", value: "198.51.100.1", name: "Existing")
      file = Tempfile.new(["rules", ".json"])
      file.write(JSON.generate({"rules" => [{"kind" => "honeypot", "path" => "/.env", "name" => "Env probe"}]}))
      file.rewind

      post "/parry/rules/import", params: {
        file: Rack::Test::UploadedFile.new(file.path, "application/json")
      }

      assert_redirected_to "/parry/rules"
      assert_equal ["Env probe", "Existing"], Parry.store.all.map(&:name).sort
    ensure
      file&.close!
    end

    test "replacing every rule from a file" do
      create_rule(kind: "blocklist", value: "198.51.100.1", name: "Existing")

      post "/parry/rules/import", params: {
        mode: "replace",
        pasted: JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "203.0.113.4", "name" => "Imported"}]})
      }

      follow_redirect!
      assert_select ".parry-flash--notice", /Replaced every rule with the 1 rule from the file\./
      assert_equal ["Imported"], Parry.store.all.map(&:name)
    end

    test "a rejected import is rendered again with its complaints" do
      create_rule(kind: "blocklist", value: "198.51.100.1", name: "Existing")

      post "/parry/rules/import", params: {
        mode: "replace",
        pasted: JSON.generate({"rules" => [{"kind" => "blocklist", "value" => "not-an-ip"}]})
      }

      assert_response :unprocessable_entity
      assert_select ".parry-errors", /Value is not a valid IP address/
      assert_equal ["Existing"], Parry.store.all.map(&:name)
    end

    test "importing nothing at all asks for a file" do
      post "/parry/rules/import", params: {pasted: ""}

      assert_response :unprocessable_entity
      assert_select ".parry-errors", /Choose a file to import/
    end

    test "a round trip through the GUI" do
      create_rule(kind: "honeypot", path_match: "regex", path: "\\.(env|git)", name: "Config probe")
      create_rule(kind: "throttle", name: "logins", limit: 5, period: 60, path: "/login")

      get "/parry/rules/export"
      exported = response.body

      Parry.store.clear

      post "/parry/rules/import", params: {pasted: exported}
      follow_redirect!

      assert_select ".parry-flash--notice", /Imported 2 rules\./
      assert_equal ["Config probe", "logins"], Parry.store.all.map(&:name).sort

      get_as "203.0.113.4", "/.git/config"
      assert_response :forbidden
    end

    test "the rules page offers export and import" do
      get "/parry/rules"

      assert_select "a[href=?]", "/parry/rules/export", "Export"
      assert_select "a[href=?]", "/parry/rules/import", "Import"
    end

    test "the blocked hosts page lists what was blocked" do
      create_rule(kind: "blocklist", value: "203.0.113.4")
      get_as "203.0.113.4"

      get "/parry/blocked_hosts"

      assert_response :success
      assert_select "td", /203\.0\.113\.4/
      assert_select "td", /Blocklist: 203\.0\.113\.4/
      assert_select ".parry-tag--blocked", "Blocklisted"
    end

    test "the blocked hosts page is empty when nothing was blocked" do
      get "/parry/blocked_hosts"

      assert_response :success
      assert_select ".parry-empty", /Nothing has been blocked/
    end

    test "unblocking from the GUI removes the rule and lets the host through" do
      create_rule(kind: "blocklist", value: "203.0.113.4")
      get_as "203.0.113.4"
      assert_response :forbidden

      post "/parry/blocked_hosts/unblock", params: {ip: "203.0.113.4"}

      assert_redirected_to "/parry/blocked_hosts"
      follow_redirect!
      assert_select ".parry-flash--notice", /Unblocked 203\.0\.113\.4 and removed 1 blocklist rule/

      assert_empty Parry.store.all
      assert_empty Parry.tracker.all

      get_as "203.0.113.4"
      assert_response :success
    end

    test "unblocking a throttled host resets its counters" do
      # Scoped to a path so the throttle does not count the GUI's own requests.
      create_rule(kind: "throttle", name: "logins", limit: 1, period: 60, path: "/login")
      2.times { get_as "203.0.113.4", "/login" }
      assert_response :too_many_requests

      post "/parry/blocked_hosts/unblock", params: {ip: "203.0.113.4"}
      follow_redirect!
      assert_select ".parry-flash--notice", /reset its throttle counters/

      get_as "203.0.113.4", "/login"
      assert_response :success
    end

    # 1.2.x.y, oldest first, so the newest ends up at the top of the list.
    def record_hosts(count, at: Time.now)
      count.times do |index|
        Parry.tracker.record(
          ip: "1.2.#{index / 256}.#{index % 256}",
          match_type: "blocklist",
          rule: "Blocklist: test",
          at: at - (count - index)
        )
      end
    end

    test "the blocked hosts page shows 50 at a time" do
      record_hosts(120)

      get "/parry/blocked_hosts"

      assert_response :success
      assert_select "tbody tr", 50
      assert_select ".parry-pagination", /Showing 1-50 of 120 hosts/
      assert_select ".parry-pagination", /Page 1 of 3/
      assert_select ".parry-pagination a", "Next"
      assert_select ".parry-pagination .parry-btn--disabled", "Previous"
    end

    test "the second page carries on where the first left off" do
      record_hosts(120)

      get "/parry/blocked_hosts"
      first_page = css_select("td.parry-mono").map(&:text)

      get "/parry/blocked_hosts", params: {page: 2}

      assert_response :success
      assert_select "tbody tr", 50
      assert_select ".parry-pagination", /Showing 51-100 of 120 hosts/
      second_page = css_select("td.parry-mono").map(&:text)

      assert_empty first_page & second_page
      assert_select ".parry-pagination a", "Previous"
      assert_select ".parry-pagination a", "Next"
    end

    test "the last page holds the remainder" do
      record_hosts(120)

      get "/parry/blocked_hosts", params: {page: 3}

      assert_select "tbody tr", 20
      assert_select ".parry-pagination", /Showing 101-120 of 120 hosts/
      assert_select ".parry-pagination .parry-btn--disabled", "Next"
    end

    test "every host is listed exactly once across the pages" do
      record_hosts(120)

      seen = (1..3).flat_map do |page|
        get "/parry/blocked_hosts", params: {page: page}
        css_select("td.parry-mono").map(&:text)
      end

      assert_equal 120, seen.size
      assert_equal 120, seen.uniq.size
    end

    test "a page past the end lands on the last one" do
      record_hosts(60)

      get "/parry/blocked_hosts", params: {page: 99}

      assert_response :success
      assert_select ".parry-pagination", /Page 2 of 2/
      assert_select "tbody tr", 10
    end

    test "a nonsense page lands on the first one" do
      record_hosts(60)

      ["0", "-3", "abc", ""].each do |page|
        get "/parry/blocked_hosts", params: {page: page}

        assert_response :success
        assert_select ".parry-pagination", /Page 1 of 2/
      end
    end

    test "there are no page controls when everything fits" do
      record_hosts(50)

      get "/parry/blocked_hosts"

      assert_select "tbody tr", 50
      assert_select ".parry-pagination", /Showing 1-50 of 50 hosts/
      assert_select ".parry-pagination-controls", false
    end

    test "caught hosts are paginated alongside the tracked ones" do
      record_hosts(49)
      rule = create_rule(kind: "honeypot", path: "/.env", name: "Env probe")
      Parry.honeypots.record("203.0.113.9", rule: rule, path: "/.env", at: Time.now)

      get "/parry/blocked_hosts"

      # The caught host is the most recent, so it heads the first page.
      assert_select "tbody tr", 50
      assert_select ".parry-pagination", /Showing 1-50 of 50 hosts/
      assert_select "tbody tr:first-child td.parry-mono", "203.0.113.9"
    end

    test "unblocking returns to the page it was done from" do
      record_hosts(120)
      victim = Parry.tracker.all(limit: 200)[60].ip

      post "/parry/blocked_hosts/unblock", params: {ip: victim, page: 2}

      assert_redirected_to "/parry/blocked_hosts?page=2"
      follow_redirect!
      assert_select ".parry-flash--notice", /Unblocked #{Regexp.escape(victim)}/
    end

    test "unblocking from the first page keeps the page out of the URL" do
      record_hosts(10)

      post "/parry/blocked_hosts/unblock", params: {ip: "1.2.0.1", page: 1}

      assert_redirected_to "/parry/blocked_hosts"
    end

    test "a caught host is listed and can be unblocked" do
      create_rule(kind: "honeypot", path: "/.env", name: "Env probe")
      get_as "203.0.113.4", "/.env"
      assert_response :forbidden

      get "/parry/blocked_hosts"
      assert_response :success
      assert_select ".parry-tag--caught", "Caught"
      assert_select "td", /Honeypot: Env probe/

      post "/parry/blocked_hosts/unblock", params: {ip: "203.0.113.4"}
      follow_redirect!
      assert_select ".parry-flash--notice", /released it from the honeypot/

      get_as "203.0.113.4", "/"
      assert_response :success
    end

    test "caught hosts are listed even when event tracking is off" do
      rule = create_rule(kind: "honeypot", path: "/.env")
      Parry.honeypots.record("203.0.113.4", rule: rule, path: "/.env")

      get "/parry/blocked_hosts"

      assert_response :success
      assert_select "td", /203\.0\.113\.4/
      assert_select ".parry-tag--caught", "Caught"
    end

    test "unblocking without an address" do
      post "/parry/blocked_hosts/unblock", params: {ip: ""}

      assert_redirected_to "/parry/blocked_hosts"
      follow_redirect!
      assert_select ".parry-flash--alert", /No host given/
    end
  end
end
