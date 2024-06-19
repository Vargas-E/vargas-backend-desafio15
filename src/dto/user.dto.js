class UserDto {
  constructor({ first_name, last_name, age, rol, cart, email }) {
    this.first_name = first_name;
    this.last_name = last_name;
    this.age = age;
    this.rol = rol;
    this.age = age;
    this.cart = cart;
    this.email = email;
  }
}

module.exports = UserDto;
