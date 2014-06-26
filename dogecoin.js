(function (exports) {
  var Dogecoin = exports;

  if ('object' !== typeof module) {
    Dogecoin.EventEmitter = EventEmitter;
  }
})(
  'object' === typeof module ? module.exports : (window.Dogecoin = {})
);