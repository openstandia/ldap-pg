// +build !integration

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/openstandia/goldap/message"
)

type ToQueryTestByFullJsonData struct {
	label     string
	schemaMap SchemaMap
	filter    message.Filter
	err       string
	out       *Query
}

func TestToQueryByFullJson(t *testing.T) {
	server := NewServer(&ServerConfig{
		Suffix:          "dc=example,dc=com",
		QueryTranslator: "fulljson",
	})
	schemaMap = InitSchemaMap(server)
	for i, test := range getToQueryByFullTestData() {
		q, err := ToQuery(server, test.schemaMap, test.filter)
		if err == nil {
			if test.out == nil {
				t.Errorf("#%d: %s\nEXPECTED ERROR MESSAGE:\n%s\nGOT A STRUCT INSTEAD:\n%#+v", i, test.label, test.err, q)
			} else if !reflect.DeepEqual(*q, *test.out) {
				t.Errorf("#%d: %s\nGOT:\n%#+v\nEXPECTED:\n%#+v", i, test.label, q, test.out)
			}
		} else if !strings.Contains(err.Error(), test.err) {
			t.Errorf("#%d: %s\nGOT:\n%s\nEXPECTED:\n%s", i, test.label, err.Error(), test.err)
		}
	}
}

func getToQueryByFullTestData() (ret []ToQueryTestByFullJsonData) {
	return []ToQueryTestByFullJsonData{
		{
			label: "cn=foo",
			schemaMap: map[string]*Schema{
				"cn": {
					Name:        "cn",
					Equality:    "",
					SingleValue: true,
				},
			},
			filter: message.NewFilterEqualityMatch("cn", "foo"),
			out: &Query{
				Query: "e.attrs_norm @@ :filter",
				Params: map[string]interface{}{
					"filter": `$.cn == "foo"`,
				},
				PendingParams:   map[*DN]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(&(cn=foo)(uid=foo))",
			schemaMap: map[string]*Schema{
				"cn": {
					Name:        "cn",
					Equality:    "",
					SingleValue: true,
				},
				"uid": {
					Name:        "uid",
					Equality:    "",
					SingleValue: true,
				},
			},
			filter: message.FilterAnd{
				message.NewFilterEqualityMatch("cn", "foo"),
				message.NewFilterEqualityMatch("uid", "bar"),
			},
			out: &Query{
				Query: "e.attrs_norm @@ :filter",
				Params: map[string]interface{}{
					"filter": `($.cn == "foo" && $.uid == "bar")`,
				},
				PendingParams:   map[*DN]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(|(cn=foo)(cn=bar))",
			schemaMap: map[string]*Schema{
				"cn": {
					Name:        "cn",
					Equality:    "",
					SingleValue: true,
				},
			},
			filter: message.FilterOr{
				message.NewFilterEqualityMatch("cn", "foo"),
				message.NewFilterEqualityMatch("cn", "bar"),
			},
			out: &Query{
				Query: "e.attrs_norm @@ :filter",
				Params: map[string]interface{}{
					"filter": `($.cn == "foo" || $.cn == "bar")`,
				},
				PendingParams:   map[*DN]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(|(cn=foo)(cn=bar)(cn=hoge))",
			schemaMap: map[string]*Schema{
				"cn": {
					Name:        "cn",
					Equality:    "",
					SingleValue: true,
				},
			},
			filter: message.FilterOr{
				message.NewFilterEqualityMatch("cn", "foo"),
				message.NewFilterEqualityMatch("cn", "bar"),
				message.NewFilterEqualityMatch("cn", "hoge"),
			},
			out: &Query{
				Query: "e.attrs_norm @@ :filter",
				Params: map[string]interface{}{
					"filter": `($.cn == "foo" || $.cn == "bar" || $.cn == "hoge")`,
				},
				PendingParams:   map[*DN]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(|(cn=foo)(&(uid=bar)(sn=hoge)))",
			schemaMap: map[string]*Schema{
				"cn": {
					Name:        "cn",
					Equality:    "",
					SingleValue: true,
				},
				"uid": {
					Name:        "uid",
					Equality:    "",
					SingleValue: true,
				},
				"sn": {
					Name:        "sn",
					Equality:    "",
					SingleValue: true,
				},
			},
			filter: message.FilterOr{
				message.NewFilterEqualityMatch("cn", "foo"),
				message.FilterAnd{
					message.NewFilterEqualityMatch("uid", "bar"),
					message.NewFilterEqualityMatch("sn", "hoge"),
				},
			},
			out: &Query{
				Query: "e.attrs_norm @@ :filter",
				Params: map[string]interface{}{
					"filter": `($.cn == "foo" || ($.uid == "bar" && $.sn == "hoge"))`,
				},
				PendingParams:   map[*DN]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(!(cn=foo))",
			schemaMap: map[string]*Schema{
				"cn": {
					Name:        "cn",
					Equality:    "",
					SingleValue: true,
				},
			},
			filter: message.FilterNot{
				Filter: message.NewFilterEqualityMatch("cn", "foo"),
			},
			out: &Query{
				Query: "e.attrs_norm @@ :filter",
				Params: map[string]interface{}{
					"filter": `(!($.cn == "foo"))`,
				},
				PendingParams:   map[*DN]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},
	}
}
