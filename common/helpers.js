if (!Array.prototype.flatten) {
    Array.prototype.flatten = function () {
        return Array.prototype.concat.apply([], this);
    }
}