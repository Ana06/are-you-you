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
# Copy the code in a Ruby console or run it by executing (tried with Ruby 2.6):
# ruby script-generate-queries.rb


# Generates the documents touched query for osquery
def documents_query
  extensions =['.pdf', '.doc', '.docx', '.ppt', '.xls', '.txt', '.html', '.htm', '.rtf', '.txt', '.odt', '.ods', '.xlsx', '.pptx']
  query_string = "SELECT count(*) as number, GROUP_CONCAT (DISTINCT target_path) as paths FROM file_events WHERE action IN ('UPDATED', 'ATTRIBUTES_MODIFIED') AND ("
  extensions.each do |ext|
    query_string += "target_path LIKE '%#{ext}'"
    query_string += " OR " unless ext == extensions[-1]
  end
  query_string
end

# Generates the decoys activated query for osquery
def decoys_query
  files = ['/home/ana/.cache/chromium/Default/Cache/079a095ca14f7de8_0', '/home/ana/.cache/thumbnails/normal/90c5e742ec9cdbf5d6438d925b6be581.png', '/home/ana/.cache/mozilla/firefox/n6fu3vn8.default/cache2/entries/DF9CD2700FCD8A7CEA62A713D59BE159882AD1F6', '/home/ana/.local/share/okular/docdata/1191240.RUU_Journal2.pdf.xml', '/home/ana/.cache/chromium/Default/Code Cache/js/c28d3175660a2d80_0', '/home/ana/.pyenv/versions/3.5.3/lib/python3.5/test/__pycache__/threaded_import_hangers.cpython-65.opt-2.pyc', '/home/ana/.pyenv/versions/3.5.3/lib/python3.5/test/zip_cp4398_header.zip', '/home/ana/.bundle/cache/compact_index/rubygems.org.443.29b0360b937aa4d161703e6160654e47/info/protobf-cucumber', '/home/ana/Documents/uni/1-semester/analysis_of_algorithms/lectures/23 approx.pdf', '/home/ana/.password']
  query_string = "SELECT count(*) as number, GROUP_CONCAT (DISTINCT target_path) as paths FROM file_events WHERE"
  files.each do |f|
    query_string += " target_path = '#{f}'"
    query_string += " OR" unless f == files[-1]
  end
  query_string
end

# Generates the shell commands query for osquery
def commands_query
  commands = ['sudo', 'la', 'vim', 'cd', 'git', 'open', 'cp', 'driveup', 'irb']
  case_s = 'CASE'
  commands.each { |command, i| case_s += " WHEN command LIKE '#{command}%' THEN '#{command}'" }
  case_s += " ELSE 'other' END"
  "SELECT #{case_s} AS command, COUNT(*) AS number FROM shell_history GROUP BY #{case_s}"
end

puts 'DOCUMENTS QUERY'
puts documents_query
puts "\nDECOYS QUERY"
puts decoys_query
puts "\nCOMMANDS QUERY"
puts commands_query

