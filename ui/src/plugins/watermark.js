function truncateCenter(s, l) {
	if (s.length <= l) {
		return s;
	}
	let centerIndex = Math.ceil(l / 2);
	return s.slice(0, centerIndex - 2) + '...' + s.slice(centerIndex + 1, l);
}

export function canvasWaterMark(container, content, width, height, textAlign, textBaseline, alpha, font, fillStyle, rotate, zIndex) {
	container = container || document.body;
	width = width || 300;
	height = height || 300;
	textAlign = textAlign || 'center';
	textBaseline = textBaseline || 'middle';
	alpha = alpha || 0.3;
	font = font || '20px monaco, microsoft yahei';
	fillStyle = fillStyle || 'rgba(184, 184, 184, 0.8)';
	content = content || 'DIYLink';
	rotate = rotate || -45;
	zIndex = zIndex || 1000;
	let canvas = document.createElement('canvas');
	let ctx = canvas.getContext('2d');
	if (!ctx) {
		return;
	}

	canvas.width = width;
	canvas.height = height;
	ctx.globalAlpha = 0.5;

	ctx.font = font;
	ctx.fillStyle = fillStyle;
	ctx.textAlign = textAlign;
	ctx.textBaseline = textBaseline;
	ctx.globalAlpha = alpha;

	ctx.translate(0.5 * width, 0.5 * height);
	ctx.rotate((rotate * Math.PI) / 180);

	function generateMultiLineText(_ctx, _text, _width, _lineHeight) {
		let words = _text.split('\n');
		let line = '';
		let x = 0;
		let y = 0;
		for (let n = 0; n < words.length; n++) {
			line = words[n];
			line = truncateCenter(line, 25);
			_ctx.fillText(line, x, y);
			y += _lineHeight;
		}
	}

	generateMultiLineText(ctx, content, width, 24);

	// 删除已存在的
	let watermarkChild = container.firstChild;
	if (watermarkChild?.className === 'watermark-box') {
		container.removeChild(watermarkChild);
	}

	let base64Url = canvas.toDataURL();
	let watermarkDiv = document.createElement('div');
	let config = {attributes: true};

	// 监听dom节点的style属性变化
	let observer = new MutationObserver((mutations) => {
		let record = mutations[0];
		if (record.type === 'attributes' && record.attributeName === 'style') {
			setTimeout(() => {
				observer.disconnect();
				// 重新添加水印
				watermarkDiv.style.width = '100%';
				watermarkDiv.style.height = '100%';
				watermarkDiv.style.backgroundImage = `url('${base64Url}')`;
				observer.observe(watermarkDiv, config);
			});
		}
	});
	observer.observe(watermarkDiv, config);

	watermarkDiv.className = 'watermark-box';
	watermarkDiv.setAttribute(
		'style',
		`
        position:absolute;
        top:0;
        left:0;
        width:100%;
        height:100%;
        z-index:${zIndex};
        pointer-events:none;
        background-repeat:repeat;
        background-image:url('${base64Url}')`
	);

	// container.style.position = 'relative';
	container.insertBefore(watermarkDiv, container.firstChild);
}