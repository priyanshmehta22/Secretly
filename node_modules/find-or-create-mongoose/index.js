const { get } = require('lodash');

module.exports = function plugin(schema) {

	schema.statics.findOrCreate = async function findOrCreate(findByQuery, createData) {
		const opts = { upsert: true, new: true };
		const writeResult = await this.update(
			findByQuery,
			{ $setOnInsert: createData },
			opts
		);

		if (get(writeResult, 'writeResult.upserted[0]._id')) {
			return this.findById(writeResult[0]._id);
		}

		return this.find(findByQuery);
	};

};
