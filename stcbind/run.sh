# generate under path-to/ondatra_deveolp
#go generate

# run stcbind test
go test -test.v -debug -testbed=./testbed/stc-stc.txt ./... -logtostderr
