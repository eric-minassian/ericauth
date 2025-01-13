watch:
	cargo lambda watch

build:
	cargo lambda build

deploy:
	cd cdk && \
	npm install && \
	npm run build && \
	npm run cdk deploy -- --require-approval never --profile eric-auth

bootstrap:
	cd cdk && \
	npm install && \
	npm run build && \
	npm run cdk bootstrap -- --profile eric-auth

login:
	aws sso login --sso-session ericminassian