# Mongoose findOrCreate plugin <atomic> [![CircleCI](https://circleci.com/gh/sam-varpass/find-or-create-mongoose/tree/master.svg?style=shield)](https://circleci.com/gh/sam-varpass/find-or-create-mongoose/tree/master)

A findOrCreate plugin that's [atomic](https://en.wikipedia.org/wiki/Atomicity_(database_systems)). A necessary characteristic for use in scaled, distributed systems. Achieved by reducing the `findOrCreate` determination to a single mongo operation.


## How To Use

#### You can set the plugin on the mongoose instance:
```
// app.js
const mongoose = require('mongoose');
const findOrCreate = requir ('find-or-create-mongoose');
mongoose.plugin(findOrCreate);
```

#### Or on individual schemas:
```
// people.model.js

const findOrCreate = require('find-or-create-mongoose');

const schema = new mongoose.Schema({
  name: { type: String },
  age: { type: Number }
});

schema.plugin(findOrCreate);

module.exports = mongoose.model('People', schema, 'people');
```

#### Then use it ...
```
// people.controller.js

const findBy = { name: 'John' };
const onCreate = { name: 'John', age: 29 };

const result = await model.findOrCreate(findBy, onCreate);

/*
 * result === {
 *	writeResult: 'create' / 'find',
 *	document: { THE_MONGO_RECORD }
 * }
**/
```

