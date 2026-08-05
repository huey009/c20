const Agent = require('../models/Agent');

module.exports = (io) => {
    if (!io) {
        console.error('Socket.io instance not provided');
        return;
    }
    
    io.on('connection', (socket) => {
        console.log('🔌 New connection:', socket.id);
        
        // Operator joins a room to watch specific agents
        socket.on('watch_agent', (agentId) => {
            socket.join(`agent_${agentId}`);
            console.log(`👁️ Watching agent: ${agentId}`);
        });
        
        // Agent connects
        socket.on('agent_connect', async (agentId) => {
            socket.join(agentId);
            console.log(`🤖 Agent connected: ${agentId}`);
            
            // Update agent status
            try {
                await Agent.findOneAndUpdate(
                    { agentId },
                    { status: 'active', lastSeen: new Date() }
                );
                
                // Notify operators
                io.emit('agent_status', { agentId, status: 'online' });
            } catch (error) {
                console.error('Error updating agent status:', error);
            }
        });
        
        // Agent disconnect
        socket.on('disconnect', async () => {
            console.log('🔌 Disconnected:', socket.id);
        });
    });
};