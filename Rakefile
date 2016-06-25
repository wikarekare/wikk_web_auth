# -*- ruby -*-

require 'rubygems'
require 'hoe'
Hoe.plugin :yard

Hoe.spec 'wikk_web_auth' do 
  self.readme_file = "README.md"
  self.developer( "Rob Burrowes","r.burrowes@auckland.ac.nz")
  remote_rdoc_dir = '' # Release to root
  
  self.yard_title = 'wikk_web_auth'
  self.yard_options = ['--markup', 'markdown', '--protected']
end


#Validate manfest.txt
#rake check_manifest

#Local checking. Creates pkg/
#rake gem

#create doc/
#rake docs  

#Copy up to rubygem.org
#rake release VERSION=1.0.1
