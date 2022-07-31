#! /usr/bin/env ruby
# frozen_string_literal: true

#
#   check-ports-nmap
#
# DESCRIPTION:
#   Fetch port status using nmap. This check is good for catching bad network ACLs
#   or service down events for network resources. All ports are TCP SYN scanned.
#   Extra ports can be specified for UDP scans.
#
# OUTPUT:
#   plain text
#
# PLATFORMS:
#   Linux, Windows, BSD, Solaris, etc
#
# DEPENDENCIES:
#   gem: sensu-plugin
#   nmap package
#
# USAGE:
#   $ ./check-ports-nmap.rb --host some_server --open_ports 22,8080 --udp_ports 53 --level crit
#
# NOTES:
#   #YELLOW
#   Look at rewriting this using the namp library to not depend on external tools
#
# LICENSE:
#   Copyright 2013 GoDaddy.com, LLC <jjmanzer@godaddy.com>
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'open3'
require 'sensu-plugin/check/cli'
require 'json'

# CheckPorts
class CheckPorts < Sensu::Plugin::Check::CLI
  option :host,
         description: 'Resolving name or IP address of target host',
         short: '-h HOST',
         long: '--host HOST',
         default: 'localhost'

  option :scan_ports,
         description: 'Port(s) to scan',
         short: '-s PORT,PORT...',
         long: '--scan_ports PORT,PORT...'

  option :open_ports,
         description: 'Port(s) expected to be open',
         short: '-o PORT,PORT...',
         long: '--open_ports PORT,PORT...'

  option :level,
         description: 'Alert level crit(critical) or warn(warning)',
         short: '-l crit|warn',
         long: '--level crit|warn',
         required: false,
         default: 'WARN'

  def run
    stdout, stderr = Open3.capture3(
      ENV,
      "nmap -Pn -p #{config[:scan_ports]} #{config[:host]}"
    )

    case stderr
    when /Failed to resolve/
      critical 'cannot resolve the target hostname'
    end

    open_ports_array = config[:open_ports].split(",").map(&:to_i)
    # ok open_ports_array - CheckPorts OK: [22, 30303]
    port_checks = {}
    check_pass  = true

    stdout.split("\n").each do |line|
      line.scan(/(\d+).tcp\s+(\S+)\s+(\S+)/).each do |status|
        port_checks[status[1]] ||= []
        port_checks[status[1]].push status[0]
        if open_ports_array.include?(status[0].to_i)
          check_pass = false unless status[1]['open']
        else
          check_pass = false if status[1]['open']
        end
      end
    end

    result = port_checks.map { |state, ports| "#{state}:#{ports.join(',')}" }.join(' ')

    if check_pass
      ok result
    elsif config[:level].casecmp('WARN').zero?
      warning result
    elsif config[:level].casecmp('CRIT').zero?
      critical result
    else
      unknown "Unknown alert level #{config[:level]}"
    end
  end
end
