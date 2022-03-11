# OWASP ZAP CLI in Ruby

## Prerequisites

- Ruby v2 or later
- OWASP ZAP
  - https://www.zaproxy.org/download/
- Generate a new zap-api.json file
  - https://github.com/jmeit/zap-api-generator
- Copy ZAP API key into example.rb and update port number if it's not 8081
  - https://www.zaproxy.org/docs/api/#basics-on-the-api-request

## Usage

- Open OWASP ZAP
- Update eureka-dynamic.yaml with necessary config options
- Run example.rb

## To Do

- Update this readme with more usage details regarding:
  - Context and Policy Files
  - auth.sh
  - Login url + creds
  - graphql
  - postman
  - and more...

## Notes
Don't bug me about the API key in the source code. I know it's there. It's for using ZAP locally, and only works while it's running on my test machine. Everything is fine. Cool your jets, hot stuff.