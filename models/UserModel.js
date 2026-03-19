const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  accountId: String,
  // active: {
  //   type: Boolean,
  //   default: true,
  //   select: false,
  // },
});

// userSchema.pre(/^find/, function (next) {
//   // this points to the current query
//   this.find({ active: { $ne: false } });
//   next();
// });

const User = mongoose.model("User", userSchema);

module.exports = User;
