const dns = require('dns');

const { Resolver } = require('dns');
const resolver = new Resolver();
resolver.setServers(['127.0.0.1:53']);

function get_domain() {
	let s = ''
	for(i = 0; i < Math.floor(Math.random()*10) + 3; i++) {
		s += String.fromCharCode(Math.floor(Math.random()*25+65));
	}
	return s.toLowerCase()+'.com'
}

function get_rptr() {
	return (Math.floor(Math.random()*255)+1) + '.' + 
			(Math.floor(Math.random()*255)+1) + '.' +
			(Math.floor(Math.random()*255)+1) + '.' +
			(Math.floor(Math.random()*255)+1) + '.in-addr.arpa.' 

}

for(let i = 0; i < 1000000; i++) {
	resolver.resolve4(get_domain(), () => {});
	resolver.resolveNs(get_domain(), () => {});
	resolver.resolveCname(get_domain(), () => {});
	resolver.resolveSoa(get_domain(), () => {});
	resolver.resolvePtr(get_rptr(), () => {});
	resolver.resolveMx(get_domain(), () => {});
	resolver.resolveTxt(get_domain(), () => {});
	resolver.resolveSrv(get_domain(), () => {});
	// spf..
}
