# encoding: utf-8
require 'spec_helper'
require "logstash/filters/ipip"

describe LogStash::Filters::IPIP do
  describe "Test ip 8.8.8.8" do
    let(:config) do <<-CONFIG
      filter {
        ipip {
          source => "ip"
        }
      }
    CONFIG
    end

    sample("ip" => "8.8.8.8") do
      insist { subject }.include?("ipip")

      expected_fileds = %w(country province city carrier)
      expected_fileds.each do |f|
        insist { subject["ipip"] }.include?(f)
      end
    end
  end

  describe "Specify the target" do
    let(:config) do <<-CONFIG
      filter {
        ipip {
          source => "ip"
          target => src_ip
        }
      }
    CONFIG
    end

    sample("ipip" => "8.8.8.8") do
      insist { subject }.include?("src_ip")

      expected_fileds = %w(country province city carrier)
      expected_fileds.each do |f|
        insist { subject["src_ip"] }.include?(f)
      end
    end
  end
end
