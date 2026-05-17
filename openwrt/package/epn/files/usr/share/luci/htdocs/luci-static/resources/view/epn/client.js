'use strict';
'require form';
'require fs';
'require poll';
'require uci';
'require view';

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('epn'),
			fs.exec('/usr/libexec/epn-status', []).catch(function(e) { return e; })
		]);
	},

	render: function(data) {
		var m, s, o, statusBox;
		var status = {};

		try {
			status = JSON.parse((data[1] && data[1].stdout) || '{}');
		} catch (e) {
			status = {};
		}

		m = new form.Map('epn', _('EPN Client'));
		m.on_after_commit = L.bind(function() {
			return fs.exec('/etc/init.d/epn', [ 'restart' ]).then(L.bind(this.refreshStatus, this)).catch(function() {});
		}, this);

		s = m.section(form.NamedSection, 'main', 'client', _('Router client'));
		s.anonymous = true;

		statusBox = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Status')),
			E('p', { 'id': 'epn-status-line' }, this.formatStatus(status)),
			E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': this.pingDiscovery.bind(this)
			}, _('Ping discovery server'))
		]);
		m.render = L.bind(function(render) {
			return render.call(m).then(function(node) {
				node.insertBefore(statusBox, node.firstChild);
				return node;
			});
		}, this, m.render);

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '0';

		o = s.option(form.Value, 'disc_host', _('Discovery host'));
		o.datatype = 'host';
		o.placeholder = '203.0.113.10';
		o.rmempty = false;

		o = s.option(form.Value, 'disc_port', _('Discovery port'));
		o.datatype = 'port';
		o.default = '8000';
		o.rmempty = false;

		o = s.option(form.Value, 'relays', _('Relay hops'));
		o.datatype = 'uinteger';
		o.default = '3';
		o.rmempty = false;

		o = s.option(form.Value, 'socks_bind', _('SOCKS bind address'));
		o.datatype = 'ipaddr';
		o.default = '0.0.0.0';
		o.rmempty = false;

		o = s.option(form.Value, 'socks_port', _('SOCKS port'));
		o.datatype = 'port';
		o.default = '1080';
		o.rmempty = false;

		o = s.option(form.Flag, 'transparent', _('Transparent mode'));
		o.default = '0';

		o = s.option(form.Value, 'tproxy_port', _('Transparent proxy port'));
		o.datatype = 'port';
		o.default = '1081';
		o.depends('transparent', '1');

		o = s.option(form.Flag, 'debug', _('Debug logging'));
		o.default = '0';

		poll.add(L.bind(this.refreshStatus, this), 5);
		return m.render();
	},

	formatStatus: function(status) {
		var parts = [];
		parts.push(status.enabled ? _('enabled') : _('disabled'));
		parts.push(status.running ? _('service running') : _('service stopped'));
		parts.push(status.socks_ready ? _('SOCKS ready') : _('SOCKS not ready'));
		if (status.discovery)
			parts.push(_('discovery') + ': ' + status.discovery);
		if (status.socks)
			parts.push(_('SOCKS') + ': ' + status.socks);
		return parts.join(' | ');
	},

	refreshStatus: function() {
		var line = document.getElementById('epn-status-line');
		if (!line)
			return Promise.resolve();

		return fs.exec('/usr/libexec/epn-status', []).then(L.bind(function(res) {
			var status = {};
			try {
				status = JSON.parse(res.stdout || '{}');
			} catch (e) {}
			line.textContent = this.formatStatus(status);
		}, this)).catch(function() {
			line.textContent = _('Status is unavailable');
		});
	},

	pingDiscovery: function(ev) {
		var button = ev.currentTarget;
		var line = document.getElementById('epn-status-line');
		button.disabled = true;

		return uci.load('epn').then(function() {
			var host = uci.get('epn', 'main', 'disc_host') || '';
			var port = uci.get('epn', 'main', 'disc_port') || '8000';
			return fs.exec('/usr/libexec/epn-ping', [ host, port, '3' ]);
		}).then(function(res) {
			var ping = {};
			try {
				ping = JSON.parse(res.stdout || '{}');
			} catch (e) {}
			line.textContent = ping.message || _('Discovery endpoint is reachable');
		}).catch(function(e) {
			var ping = {};
			try {
				ping = JSON.parse((e && e.stdout) || '{}');
			} catch (err) {}
			line.textContent = ping.message || _('Discovery endpoint is not reachable');
		}).finally(function() {
			button.disabled = false;
		});
	}
});
