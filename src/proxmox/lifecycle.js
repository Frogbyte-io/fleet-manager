// src/proxmox/lifecycle.js
export async function getPowerState(client, node, vmid) {
  if (vmid === null || vmid === undefined) return 'unmanaged';
  const status = await client.request('GET', `/nodes/${node}/qemu/${vmid}/status/current`);
  return status.status;
}

export async function cloneFromTemplate(client, node, { templateVmid, newVmid, name }) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${templateVmid}/clone`, { newid: newVmid, name });
  return client.waitForTask(node, upid);
}

export async function rollbackSnapshot(client, node, vmid, snapshotName) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${vmid}/snapshot/${snapshotName}/rollback`);
  return client.waitForTask(node, upid);
}

export async function startMachine(client, node, vmid) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${vmid}/status/start`);
  return client.waitForTask(node, upid);
}

export async function stopMachine(client, node, vmid) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${vmid}/status/stop`);
  return client.waitForTask(node, upid);
}

export async function createVm(client, node, {
  vmid, name, cores, memoryMb, diskGb, storage, bridge, isoVolid, ostype = 'l26',
}) {
  const upid = await client.request('POST', `/nodes/${node}/qemu`, {
    vmid,
    name,
    cores,
    memory: memoryMb,
    net0: `virtio,bridge=${bridge}`,
    scsihw: 'virtio-scsi-pci',
    scsi0: `${storage}:${diskGb}`,
    ide2: `${isoVolid},media=cdrom`,
    ostype,
    boot: 'order=ide2;scsi0',
  });
  return client.waitForTask(node, upid);
}

export async function resetMachine(client, node, machine) {
  const strategy = machine.lifecycle?.reset_strategy;
  if (strategy === 'snapshot') {
    return rollbackSnapshot(client, node, machine.vmid, 'golden');
  }
  if (strategy === 'clone') {
    throw new Error('clone reset_strategy requires template/newVmid wiring — call cloneFromTemplate directly with the machine\'s base_template vmid');
  }
  throw new Error(`Unsupported reset_strategy "${strategy}" for machine ${machine.vmid}`);
}
