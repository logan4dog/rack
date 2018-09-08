.PHONY: all clean release test

TEST_FUNCTION:=

all: lambda.zip

lambda.zip: handler
	zip -r lambda.zip handler

handler: *.go
	GOOS=linux GOARCH=amd64 go build -o handler

clean:
	rm -f lambda.zip handler

release: lambda.zip
	for region in $(shell cat ../../../../REGIONS); do \
		aws s3 cp lambda.zip s3://convox-$$region/release/$(VERSION)/lambda/certificate.zip --acl public-read --region $$region; \
	done

test: lambda.zip
	aws s3 cp lambda.zip s3://$(BUCKET)/lambda/certificate/handler.zip
	aws cloudformation create-stack --stack-name certtest-$(shell date +%s) --template-body file://formation.yml --parameters ParameterKey=Bucket,ParameterValue=$(BUCKET) --capabilities CAPABILITY_IAM
