# frozen_string_literal: true

module Parry
  module ApplicationHelper
    def parry_time(time)
      return "—" if time.nil?

      tag.span("#{time_ago_in_words(time)} ago", title: time.strftime("%Y-%m-%d %H:%M:%S %Z"))
    end

    def parry_period(seconds)
      return "—" if seconds.nil?

      distance_of_time_in_words(seconds.to_i)
    end

    def parry_kind_label(kind)
      tag.span(kind.to_s.titleize, class: "parry-tag parry-tag--#{kind}")
    end
  end
end
