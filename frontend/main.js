// frontend/main.js – fetch data and render graph without auth
import cytoscape from 'https://unpkg.com/cytoscape@3.24.0/dist/cytoscape.esm.min.js';

const graphContainer = document.getElementById('graphContainer');

function renderGraph(elements) {
  const cy = cytoscape({
    container: graphContainer,
    elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'var(--primary)',
          label: 'data(label)',
          color: '#fff',
          'text-outline-width': 2,
          'text-outline-color': '#000',
          'font-size': '12px',
        },
      },
      {
        selector: 'edge',
        style: {
          width: 2,
          'line-color': 'var(--accent)',
          'target-arrow-color': 'var(--accent)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
        },
      },
    ],
    layout: { name: 'cose', animate: true, animationDuration: 500 },
  });
}

async function search(query) {
  const resp = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
  const data = await resp.json();
  if (data.success) {
    const elements = [];
    data.data.forEach(rec => {
      const node = rec.n;
      elements.push({ data: { id: node.identity.low || node.identity, label: node.properties.name } });
    });
    for (let i = 0; i < elements.length - 1; i++) {
      elements.push({ data: { source: elements[i].data.id, target: elements[i + 1].data.id } });
    }
    renderGraph(elements);
  } else {
    alert('Search failed');
  }
}

document.getElementById('searchBtn').addEventListener('click', () => {
  const q = document.getElementById('searchInput').value.trim();
  if (q) search(q);
});
