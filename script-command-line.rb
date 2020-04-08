# Copyright (C) 2020 Ana Maria Martinez Gomez <anamaria@martinezgomez.name>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, see <https://www.gnu.org/licenses>.
#
# SPDX-License-Identifier: GPLv3-or-later

# INSTRUCTIONS
# To run it just execute (tried with Ruby 2.6):
# ruby script-command-line.rb
#
# It is a script to generate statistics about the shell history.
#
# The file 'history-commands' must contain the shell history
# (.bash_history or .zsh_history without timestamps)


$N = 9
hash = Hash.new(0)
total = 0

File.foreach('history-commands') do |command|
  next if command.empty?
  hash[command.split.first] += 1
  total += 1
end

results = hash.sort_by { |_, n| -n }

puts "#{total} command executed. Most common ones:"
results[0..($N-1)].each_with_index do |(command, number), i|
  puts "  #{i}. #{command} - #{number}"
end
