package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//here we store data of users, we can also connection database here
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

//create the JWT key which would create the signature
var jwtkey = []byte("krish@knight8")

//creating struct to read username and password from the request body
type Credential struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

//creating a struct which will be encoded to JWT
//We add jwt.StandardClaims as an embeded type, to provide fields like expiry time
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

//creating signin handler
func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credential

	//getting credentials from JSON body
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//getting the expected password from the map, expectedpassword take the value which is the password
	//correspond to the username
	expectedpassword, ok := users[creds.Username]

	//if the password is not right,
	if !ok || expectedpassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//if the login is valid
	//declaring the expiration time of token, which is 5 minutes
	expirationtime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationtime.Unix(),
		},
	}

	//Declare token with algorithm used for signing, and the claims
	//this NewWithClaims has header(alogorithm,type), takes our username as payload create a string
	// with the help of secret key
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	//create jwt string of the token
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println(tokenString)

	//finally, we set the client cookie for "token" as JWT we just generated
	//we also set an expiration time
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationtime,
	})

}

func Welcome(w http.ResponseWriter, r *http.Request) {
	//we are obtaining session token from the http cookies inside the request
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			//no cookie present
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		//for other errors
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//getting the JWT String from cookie
	tokenString := c.Value

	var claims Claims

	tken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtkey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tken.Valid {
		w.WriteHeader(http.StatusUnauthorized)
	}

	//for valid token we shows a welcome message
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	//getting the token from the cookie
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenString := c.Value

	var claims Claims

	tken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtkey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tken.Valid {
		w.WriteHeader(http.StatusUnauthorized)
	}

	//issuing new token when the old token will be expiring within 30s
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		//return bad request when old token is not in last 30s to expires
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//creating new token, within renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenstring, err := token.SignedString(jwtkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//set the new token as the users `token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenstring,
		Expires: expirationTime,
	})
}
