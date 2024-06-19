const {Command} = require("commander");
const program = new Command();

program.option("--mode <mode>", "work env", "produccion")
program.parse();


module.exports = program;
