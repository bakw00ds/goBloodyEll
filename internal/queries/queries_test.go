package queries

import "testing"

func TestOrder(t *testing.T) {
	in := []Query{
		{ID: "x", Category: "INFO"},
		{ID: "ad-domain-controllers", Category: "AD"},
		{ID: "ad-domain-admins", Category: "AD"},
		{ID: "ad-all-users-samaccountname", Category: "AD"},
		{ID: "ad-all-computers-fqdn", Category: "AD"},
		{ID: "y", Category: "AD"},
		{ID: "z", Category: "EntraID"},
	}
	out := Order(in)
	want := []string{"ad-all-users-samaccountname", "ad-all-computers-fqdn", "ad-domain-admins", "ad-domain-controllers"}
	for i, id := range want {
		if out[i].ID != id {
			t.Fatalf("pos %d want %s got %s", i, id, out[i].ID)
		}
	}
}
