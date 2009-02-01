use Config;

$option = $ARGV[0];

if ($option eq "--flags") {
	print "-I$Config{archlib}/CORE $Config{ccflags} $Config{cccdlflags}";
}



