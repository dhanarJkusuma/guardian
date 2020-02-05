package password

import "golang.org/x/crypto/bcrypt"

func hash(str string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(str), 10)
	return string(hashedPassword)
}

func compareHash(storedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	return err == nil
}
