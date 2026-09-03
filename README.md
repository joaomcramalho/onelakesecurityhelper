# OneLake Security Explorer

An interactive educational website that explains how Microsoft Fabric and OneLake permissions combine across:

- Microsoft Entra identities and groups
- Fabric workspace roles
- Lakehouse item permissions and sharing
- OneLake security roles
- SQL analytics endpoint permissions
- Direct Lake on OneLake semantic model permissions, SSO, and fixed identities
- OneLake and semantic-model RLS/OLS interaction
- Shortcuts and target access

The simulator returns an effective-access result with an ordered decision trace, warnings, documentation links, and least-privilege guidance. Semantic-model coverage focuses on Direct Lake on OneLake; Import, DirectQuery, and Direct Lake on SQL have different authorization behavior and are outside the current model.

https://joaomcramalho.github.io/onelakesecurityhelper/

## Important

This is an educational rules model based on the Microsoft Learn sources linked inside the site. It does not inspect a live Fabric tenant and should not replace validation of effective permissions in the target environment.
