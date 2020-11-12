// +build !integration

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/openstandia/goldap/message"
)

type ToQueryTestData struct {
	label     string
	schemaMap SchemaMap
	filter    message.Filter
	err       string
	out       *Query
}

func TestToQuery(t *testing.T) {
	for i, test := range getToQueryTestData() {
		q, err := ToQuery(test.schemaMap, test.filter)
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

func getToQueryTestData() (ret []ToQueryTestData) {
	return []ToQueryTestData{
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
				// attrs_norm->'cn' @@ '$ == "foo"';
				Query: "e.attrs_norm->'cn' @@ :0_cn",
				Params: map[string]interface{}{
					"0_cn": `$ == "foo"`,
				},
				PendingParams:   map[string]string{},
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
				Query: "(e.attrs_norm->'cn' @@ :0_cn AND e.attrs_norm->'uid' @@ :1_uid)",
				Params: map[string]interface{}{
					"0_cn":  `$ == "foo"`,
					"1_uid": `$ == "bar"`,
				},
				PendingParams:   map[string]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(||(cn=foo)(cn=bar))",
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
				Query: "(e.attrs_norm->'cn' @@ :0_cn OR e.attrs_norm->'cn' @@ :1_cn)",
				Params: map[string]interface{}{
					"0_cn": `$ == "foo"`,
					"1_cn": `$ == "bar"`,
				},
				PendingParams:   map[string]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(||(cn=foo)(cn=bar)(cn=hoge))",
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
				Query: "(e.attrs_norm->'cn' @@ :0_cn OR e.attrs_norm->'cn' @@ :1_cn OR e.attrs_norm->'cn' @@ :2_cn)",
				Params: map[string]interface{}{
					"0_cn": `$ == "foo"`,
					"1_cn": `$ == "bar"`,
					"2_cn": `$ == "hoge"`,
				},
				PendingParams:   map[string]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},

		{
			label: "(||(cn=foo)(&&(uid=bar)(sn=hoge)))",
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
				Query: "(e.attrs_norm->'cn' @@ :0_cn OR (e.attrs_norm->'uid' @@ :1_uid AND e.attrs_norm->'sn' @@ :2_sn))",
				Params: map[string]interface{}{
					"0_cn":  `$ == "foo"`,
					"1_uid": `$ == "bar"`,
					"2_sn":  `$ == "hoge"`,
				},
				PendingParams:   map[string]string{},
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
				Query: "NOT (e.attrs_norm->'cn' @@ :0_cn)",
				Params: map[string]interface{}{
					"0_cn": `$ == "foo"`,
				},
				PendingParams:   map[string]string{},
				IdToDNOrigCache: map[int64]string{},
				DNNormToIdCache: map[string]int64{},
			},
		},
	}
}
