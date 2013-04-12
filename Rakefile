task :spec do
  system './vendor/bin/phpunit -c test/phpunit.xml --coverage-html coverage'
  system 'open coverage/index.html'
end

task default: :spec