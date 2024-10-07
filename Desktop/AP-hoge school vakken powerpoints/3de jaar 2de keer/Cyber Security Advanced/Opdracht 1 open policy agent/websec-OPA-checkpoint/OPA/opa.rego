package barmanagement #namespace
import future.keywords
default allow := false

allow if {

    is_fristi

}
allow if {
    input.request.path == "/api/bar"
    is_post
    input.request.body.DrinkName == "Beer"
    claims.age[_] > 18
    claims.role[_] == "costumer"
}

allow if {
    is_bartender
}

is_bartender {
    input.request.path == "/api/managebar"
    is_post
    input.request.body.DrinkName == "Whiskey"
    claims.age[_] > 18
    claims.role[_] == "bartender"
}

is_fristi {
    is_post
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Fristi"
}

is_post {
	input.request.method == "POST"
}

bearer_token := t {
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}

claims := payload {
	[_, payload, _] := io.jwt.decode(bearer_token)
}
