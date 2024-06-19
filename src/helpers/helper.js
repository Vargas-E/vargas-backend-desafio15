const helper = {
  jsonStringify(object) {
    if (object == undefined) {
      return `null`;
    }
    return JSON.stringify(object);
  },

  assignAppbar(user) {
    return user.rol === "admin" ? 'appbar_admin' : 'appbar';
  },

  formatDate(inputDate) {
    let date = new Date(inputDate);
    let day = ('0' + date.getDate()).slice(-2);
    let month = ('0' + (date.getMonth() + 1)).slice(-2);
    let year = date.getFullYear();
    let hours = ('0' + date.getHours()).slice(-2);
    let minutes = ('0' + date.getMinutes()).slice(-2);
    let formattedDate = day + '/' + month + '/' + year + ' ' + hours + ':' + minutes;
    return formattedDate;
  },

  ifCondOr(v1, v2, options) {
    if(v1 === v2) {
      return options.fn(this);
    }
  }
};

module.exports = helper;
