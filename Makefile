watch:
	cargo lambda watch

build:
	cargo lambda build

deploy:
	cd cdk && \
	npm install && \
	npm run build && \
	npm run cdk deploy -- --require-approval never

bootstrap:
	cd cdk && \
	npm install && \
	npm run build && \
	npm run cdk bootstrap

login:
	aws sso login --sso-session ericminassian