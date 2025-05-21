#!/bin/bash

# Make the script executable
chmod +x docker-test.sh

# Function to display help
show_help() {
    echo "OTLS Docker Test Helper"
    echo "----------------------"
    echo "Usage:"
    echo "  ./docker-test.sh [command]"
    echo ""
    echo "Commands:"
    echo "  build             Build the Docker image"
    echo "  run-single        Run a single container for local testing"
    echo "  run-multi         Run two containers for two-party testing"
    echo "  exec-single       Execute bash in the single container"
    echo "  exec-party1       Execute bash in the first party container"
    echo "  exec-party2       Execute bash in the second party container"
    echo "  clean             Stop and remove all containers"
    echo "  help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./docker-test.sh build"
    echo "  ./docker-test.sh run-single"
    echo "  ./docker-test.sh exec-single"
    echo ""
}

# Check if a command is provided
if [ $# -lt 1 ]; then
    show_help
    exit 1
fi

COMMAND=$1

case $COMMAND in
    build)
        echo "Building Docker image..."
        docker compose build
        ;;
    run-single)
        echo "Running single container for local testing..."
        docker compose up -d
        ;;
    run-multi)
        echo "Running two containers for two-party testing..."
        docker compose -f docker-compose.multi.yml up -d
        ;;
    exec-single)
        echo "Executing bash in the single container..."
        docker compose exec otls bash
        ;;
    exec-party1)
        echo "Executing bash in the first party container..."
        docker compose -f docker-compose.multi.yml exec otls1 bash
        ;;
    exec-party2)
        echo "Executing bash in the second party container..."
        docker compose -f docker-compose.multi.yml exec otls2 bash
        ;;
    clean)
        echo "Stopping and removing all containers..."
        docker compose down
        docker compose -f docker-compose.multi.yml down
        ;;
    help)
        show_help
        ;;
    *)
        echo "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac

exit 0 