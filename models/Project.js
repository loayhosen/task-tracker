const mongoose = require('mongoose');

const ProjectSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        index: true
    },
    projects: {
        type: Array,
        default: []
    }
}, { timestamps: true });

module.exports = mongoose.model('Project', ProjectSchema);