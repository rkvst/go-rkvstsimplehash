package simplehash

import v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"

// PublicFromPermissionedEvent translates the permissioned event and asset identities to
// their public counter parts.
func PublicFromPermissionedEvent(event *v2assets.EventResponse) {
	event.Identity = v2assets.PublicIdentityFromPermissioned(event.Identity)
	event.AssetIdentity = v2assets.PublicIdentityFromPermissioned(event.AssetIdentity)
}
