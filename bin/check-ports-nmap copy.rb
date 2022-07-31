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

 option :open_ports,
         description: 'Port(s) expected to be open',
         short: '-o PORT,PORT...',
         long: '--open_ports PORT,PORT...'

  option :udp_ports,
         description: 'UDP port(s) you wish to get status for',
         short: '-u PORT,PORT...',
         long: '--udp_ports PORT,PORT...'
         required: false
         default: ''

  option :level,
         description: 'Alert level crit(critical) or warn(warning)',
         short: '-l crit|warn',
         long: '--level crit|warn',
         required: false,
         default: 'WARN',

  def run
    if config[:udp_ports] != ""
      stdout, stderr = Open3.capture3(
        ENV,
        "nmap -Pn -sU -sS -p U:#{config[:udp_ports]},T:1- #{config[:host]}"
      )
    else
      stdout, stderr = Open3.capture3(
        ENV,
        "nmap -Pn -sS -p- #{config[:host]}"
      )

    case stderr
    when /Failed to resolve/
      critical 'cannot resolve the target hostname'
    end

    open_ports_array = config[:open_ports].split(",")
    port_checks = {}
    check_pass  = true

    stdout.split("\n").each do |line|
      line.scan(/(\d+).(udp|tcp)\s+(\S+)\s+(\S+)/).each do |status|
        port_checks[status[1]] ||= []
        port_checks[status[1]].push status[0]
        check_pass = false unless status[1]['open'] if not open_ports_array.include?(status[0])
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
