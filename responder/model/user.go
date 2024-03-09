package model

// User model
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (user *User) String() string {
	return "< username:" + user.Username + " password:" + user.Password + " >"
}
